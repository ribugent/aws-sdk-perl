# Generated by default/object.tt
package Paws::Organizations::DelegatedService;
  use Moose;
  has DelegationEnabledDate => (is => 'ro', isa => 'Str');
  has ServicePrincipal => (is => 'ro', isa => 'Str');

1;

### main pod documentation begin ###

=head1 NAME

Paws::Organizations::DelegatedService

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Organizations::DelegatedService object:

  $service_obj->Method(Att1 => { DelegationEnabledDate => $value, ..., ServicePrincipal => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Organizations::DelegatedService object:

  $result = $service_obj->Method(...);
  $result->Att1->DelegationEnabledDate

=head1 DESCRIPTION

Contains information about the AWS service for which the account is a
delegated administrator.

=head1 ATTRIBUTES


=head2 DelegationEnabledDate => Str

The date that the account became a delegated administrator for this
service.


=head2 ServicePrincipal => Str

The name of an AWS service that can request an operation for the
specified service. This is typically in the form of a URL, such as: C<
I<servicename>.amazonaws.com>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Organizations>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

