# Generated by default/object.tt
package Paws::KinesisVideoArchivedMedia::ClipTimestampRange;
  use Moose;
  has EndTimestamp => (is => 'ro', isa => 'Str', required => 1);
  has StartTimestamp => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::KinesisVideoArchivedMedia::ClipTimestampRange

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::KinesisVideoArchivedMedia::ClipTimestampRange object:

  $service_obj->Method(Att1 => { EndTimestamp => $value, ..., StartTimestamp => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::KinesisVideoArchivedMedia::ClipTimestampRange object:

  $result = $service_obj->Method(...);
  $result->Att1->EndTimestamp

=head1 DESCRIPTION

The range of timestamps for which to return fragments.

=head1 ATTRIBUTES


=head2 B<REQUIRED> EndTimestamp => Str

The end of the timestamp range for the requested media.

This value must be within 24 hours of the specified C<StartTimestamp>,
and it must be later than the C<StartTimestamp> value. If
C<FragmentSelectorType> for the request is C<SERVER_TIMESTAMP>, this
value must be in the past.

This value is inclusive. The C<EndTimestamp> is compared to the
(starting) timestamp of the fragment. Fragments that start before the
C<EndTimestamp> value and continue past it are included in the session.


=head2 B<REQUIRED> StartTimestamp => Str

The starting timestamp in the range of timestamps for which to return
fragments.

Only fragments that start exactly at or after C<StartTimestamp> are
included in the session. Fragments that start before C<StartTimestamp>
and continue past it aren't included in the session. If
C<FragmentSelectorType> is C<SERVER_TIMESTAMP>, the C<StartTimestamp>
must be later than the stream head.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::KinesisVideoArchivedMedia>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

