# Generated by default/object.tt
package Paws::ES::InboundCrossClusterSearchConnectionStatus;
  use Moose;
  has Message => (is => 'ro', isa => 'Str');
  has StatusCode => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::ES::InboundCrossClusterSearchConnectionStatus

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::ES::InboundCrossClusterSearchConnectionStatus object:

  $service_obj->Method(Att1 => { Message => $value, ..., StatusCode => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::ES::InboundCrossClusterSearchConnectionStatus object:

  $result = $service_obj->Method(...);
  $result->Att1->Message

=head1 DESCRIPTION

Specifies the coonection status of an inbound cross-cluster search
connection.

=head1 ATTRIBUTES


=head2 Message => Str

Specifies verbose information for the inbound connection status.


=head2 StatusCode => Str

The state code for inbound connection. This can be one of the
following:

=over

=item * PENDING_ACCEPTANCE: Inbound connection is not yet accepted by
destination domain owner.

=item * APPROVED: Inbound connection is pending acceptance by
destination domain owner.

=item * REJECTING: Inbound connection rejection is in process.

=item * REJECTED: Inbound connection is rejected.

=item * DELETING: Inbound connection deletion is in progress.

=item * DELETED: Inbound connection is deleted and cannot be used
further.

=back




=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::ES>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

